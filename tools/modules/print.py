#!/usr/bin/env python
import argparse
import json
import pathlib

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.tree import Tree

__version__ = '1.0'

RANKS = {
    600: 'Excellent',
    500: 'Great',
    400: 'Good',
    300: 'Normal',
    200: 'Average',
    100: 'Low',
    0: 'Manual'
}

framework_root = pathlib.Path(__file__).parent.parent.parent

def get_notes(module_metadata):
    tree = Tree('Notes', hide_root=True)
    for key, values in module_metadata.get('notes', {}).items():
        node = tree.add(key)
        for value in values:
            node.add(value)
    return tree

def get_description(module_metadata):
    description = ''
    paragraphs = module_metadata['description'].split('\n\n')
    for paragraph in paragraphs:
        for line in paragraph.split('\n'):
            description += line.strip() + '\n'
        description += '\n'
    return description.strip()

def get_authors(module_metadata):
    return get_bulleted_list(module_metadata['author'])

def get_targets(module_metadata):
    return get_bulleted_list(module_metadata['targets'])

def get_references(module_metadata):
    references = []
    for reference in module_metadata.get('references', []):
        if reference.startswith('URL-'):
            reference = reference[4:]
        references.append(reference)
    return get_bulleted_list(references)

def get_bulleted_list(items):
    formatted = ''
    for item in items:
        formatted += f"[bold]•[/bold] {item}\n"
    return formatted.strip()

def main():
    parser = argparse.ArgumentParser(description='fzuse helper', conflict_handler='resolve')
    parser.add_argument('module_name', help='module name to display')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
    arguments = parser.parse_args()

    with (framework_root / 'db' / 'modules_metadata_base.json').open('r') as file_h:
        all_metadata = json.load(file_h)
    module_metadata = next((metadata for metadata in all_metadata.values() if metadata['fullname'] == arguments.module_name), None)
    if not module_metadata:
        return

    table = Table(show_header=False, box=box.MINIMAL)
    table.add_column(justify='right')
    table.add_column()

    table.add_row('[bold]Name[/bold]', module_metadata['name'])
    table.add_row('[bold]Module[/bold]', module_metadata['fullname'])
    table.add_row('[bold]Platform[/bold]', module_metadata['platform'])
    table.add_row('[bold]Arch[/bold]', module_metadata['arch'])
    table.add_row('[bold]Rank[/bold]', RANKS[module_metadata['rank']])
    table.add_row('[bold]Disclosed[/bold]', module_metadata['disclosure_date'])

    console = Console()
    console.print(table)
    
    panel_title = lambda v: f"[bold]{v}[/bold]"
    console.print(Panel(get_authors(module_metadata), title=panel_title('Provided by'), title_align='left'))
    console.print(Panel(get_notes(module_metadata), title=panel_title('Notes'), title_align='left'))
    if module_metadata.get('targets'):
        console.print(Panel(get_targets(module_metadata), title=panel_title('Targets'), title_align='left'))
    console.print(Panel(get_description(module_metadata), title=panel_title('Description'), title_align='left'))
    if module_metadata.get('references'):
        console.print(Panel(get_references(module_metadata), title=panel_title('References'), title_align='left'))
    if module_metadata.get('path', ''):
        syntax = Syntax.from_path(framework_root / module_metadata['path'][1:], background_color='default', line_numbers=True)
        console.print(Panel(syntax, title=panel_title('Source code'), title_align='left'))

if __name__ == '__main__':
    main()
