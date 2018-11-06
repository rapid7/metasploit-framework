#!/usr/bin/env python

import yaml
import logging
import re
import sys

from lxml import etree

def parse_r7_remapping(file):
    with open(file) as remap_file:
        return yaml.load(remap_file)["mappings"]

def parse_cpe_vp_map(file):
    vp_map = {} # cpe_type -> vendor -> products
    parser = etree.XMLParser(remove_comments=False)
    doc = etree.parse(file, parser)
    namespaces = {'ns': 'http://cpe.mitre.org/dictionary/2.0', 'meta': 'http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2'}
    for cpe_name in doc.xpath("//ns:cpe-list/ns:cpe-item/@name", namespaces=namespaces):
        cpe_match = re.match('^cpe:/([aho]):([^:]+):([^:]+)', cpe_name)
        if cpe_match:
            cpe_type, vendor, product = cpe_match.group(1, 2, 3)
            if not cpe_type in vp_map:
                vp_map[cpe_type] = {}
            if not vendor in vp_map[cpe_type]:
                vp_map[cpe_type][vendor] = set()
            vp_map[cpe_type][vendor].add(product)
        else:
            logging.error("Unexpected CPE %s", cpe_name)

    return vp_map

def main():
    if len(sys.argv) != 4:
        logging.critical("Expecting exactly 3 arguments; recog XML file, CPE 2.3 XML dictionary, JSON remapping, got %s", (len(sys.argv) - 1))
        exit(1)

    cpe_vp_map = parse_cpe_vp_map(sys.argv[2])
    if not cpe_vp_map:
        logging.critical("No CPE vendor => product mappings read from CPE 2.3 XML dictionary %s", sys.argv[2])
        exit(1)

    r7_vp_map = parse_r7_remapping(sys.argv[3])
    if not r7_vp_map:
        logging.warning("No Rapid7 vendor/product => CPE mapping read from %s", sys.argv[3])

    update_cpes(sys.argv[1], cpe_vp_map, r7_vp_map)

def update_cpes(xml_file, cpe_vp_map, r7_vp_map):
    parser = etree.XMLParser(remove_comments=False, remove_blank_text=True)
    doc = etree.parse(xml_file, parser)

    for fingerprint in doc.xpath('//fingerprint'):

        # collect all the params, grouping by os and service params that could be used to compute a CPE
        params = {}
        for param in fingerprint.xpath('./param'):
            name = param.attrib['name']
            # remove any existing CPE params
            if re.match(r'^.*\.cpe\d{0,2}$', name):
                param.getparent().remove(param)
                continue

            match = re.search(r'^(?P<fp_type>hw|os|service(?:\.component)?)\.', name)
            if match:
                fp_type = match.group('fp_type')
                if not fp_type in params:
                    params[fp_type] = {}
                if name in params[fp_type]:
                    raise ValueError('Duplicated fingerprint named {} in {}'.format(name, fingerprint.attrib['pattern']))
                params[fp_type][name] = param


        # for each of the applicable os/service param groups, build a CPE
        for fp_type in params:
            if fp_type == 'os':
                cpe_type = 'o'
            elif fp_type.startswith('service'):
                cpe_type = 'a'
            elif fp_type == 'hw':
                cpe_type = 'h'
            else:
                raise ValueError('Unhandled param type {}'.format(fp_type))

            # extract the vendor/product/version values from each os/service group,
            # using the static value ('Apache', for example) when pos is 0, and
            # otherwise use a value that contains interpolation markers such that
            # products/projects that use recog content can insert the value
            # extracted from the banner/other data via regex capturing groups
            fp_data = {
                'vendor': None,
                'product': None,
                'version': '-',
            }
            for fp_datum in fp_data:
                fp_datum_param_name = "{}.{}".format(fp_type, fp_datum)
                if fp_datum_param_name in params[fp_type]:
                    fp_datum_e = params[fp_type][fp_datum_param_name]
                    if fp_datum_e.attrib['pos'] == '0':
                        fp_data[fp_datum] = fp_datum_e.attrib['value']
                    else:
                        fp_data[fp_datum] = "{{{}}}".format(fp_datum_e.attrib['name'])

            vendor = fp_data['vendor']
            product = fp_data['product']
            version = fp_data['version']

            # build a reasonable looking CPE value from the vendor/product/version,
            # lowercasing, replacing whitespace with _, and more
            if vendor and product:
                if not cpe_type in cpe_vp_map:
                    logging.error("Didn't find CPE type '%s' for '%s' '%s'", cpe_type, vendor, product)
                    continue

                vendor = vendor.lower().replace(' ', '_').replace(',', '')
                product = product.lower().replace(' ', '_').replace(',', '')
                if 'unknown' in [vendor, product]:
                    continue

                if (vendor.startswith('{') and vendor.endswith('}')) or (product.startswith('{') and product.endswith('}')):
                    continue

                remapped_vendor = False
                og_vendor = vendor
                if not vendor in cpe_vp_map[cpe_type]:
                    if vendor in r7_vp_map:
                        vendor = r7_vp_map[vendor]['vendor']
                        remapped_vendor = True
                        if not vendor in cpe_vp_map[cpe_type]:
                            logging.error("Remapped vendor %s (remapped from %s) invalid for CPE %s (product %s)", vendor, og_vendor, cpe_type, product)
                            continue
                    else:
                        logging.error("Vendor %s invalid for CPE %s and no remapping (product %s)", vendor, cpe_type, product)
                        continue


                # if the product as specified is not found in the CPE dictionary for this vendor
                if not product in cpe_vp_map[cpe_type][vendor]:
                    # if this vendor has a remapping from R7
                    if og_vendor in r7_vp_map and 'products' in r7_vp_map[og_vendor]:
                        # if this product has a remapping for this vendor from R7
                        if product in r7_vp_map[og_vendor]['products']:
                            og_product = product
                            product = r7_vp_map[og_vendor]['products'][product]
                            # ensure that the remapped product is valid for the given vendor in CPE
                            if not product in cpe_vp_map[cpe_type][vendor]:
                                logging.error("Remapped product %s (remapped from %s) from vendor %s invalid for CPE %s", product, og_product, vendor, cpe_type)
                                continue
                        else:
                            if remapped_vendor:
                                logging.error("Product %s from vendor %s (remapped from %s) invalid for CPE %s and no mapping", product, vendor, og_vendor, cpe_type)
                            else:
                                logging.error("Product %s from vendor %s invalid for CPE %s and no mapping", product, vendor, cpe_type)
                            continue
                    else:
                        if remapped_vendor:
                            logging.error("Vendor %s (remapped from %s) is valid for CPE %s but product %s not valid and no mapping", vendor, og_vendor, cpe_type, product)
                        else:
                            logging.error("Vendor %s is valid for CPE %s but product %s not valid and no mapping", vendor, cpe_type, product)
                        continue

                # building the CPE string
                cpe_value = 'cpe:/{}:{}:{}'.format(cpe_type, vendor, product)

                if version:
                    cpe_value += ":{}".format(version)

                cpe_param = etree.Element('param')
                cpe_param.attrib['pos'] = '0'
                cpe_param.attrib['name'] = '{}.cpe23'.format(fp_type)
                cpe_param.attrib['value'] = cpe_value

                for param_name in params[fp_type]:
                    param = params[fp_type][param_name]
                    parent = param.getparent()
                    index = parent.index(param) + 1
                    parent.insert(index, cpe_param)

    root = doc.getroot()

    with open(xml_file, 'wb') as xml_out:
        xml_out.write(etree.tostring(root, pretty_print=True, xml_declaration=True, encoding=doc.docinfo.encoding))

if __name__ == '__main__':
    try: exit(main())
    except KeyboardInterrupt: pass
