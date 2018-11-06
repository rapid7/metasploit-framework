module PatchFinder
  module Engine
    module MSU

      MICROSOFT     = 'https://www.microsoft.com'
      DOWNLOAD_MSFT = 'https://download.microsoft.com'
      TECHNET       = 'https://technet.microsoft.com'

      # These pattern checks need to be in this order.
      ADVISORY_PATTERNS = [
        # This works from MS14-001 until the most recent
        {
          check:   '//div[@id="mainBody"]//div//h2//div//span[contains(text(), "Affected Software")]',
          pattern: '//div[@id="mainBody"]//div//div[@class="sectionblock"]//table//a' 
        },
        # This works from ms03-040 until MS07-029
        {
          check:   '//div[@id="mainBody"]//ul//li//a[contains(text(), "Download the update")]',
          pattern: '//div[@id="mainBody"]//ul//li//a[contains(text(), "Download the update")]'
        },
        # This works from sometime until ms03-039
        {
          check:   '//div[@id="mainBody"]//div//div[@class="sectionblock"]//p//strong[contains(text(), "Download locations")]',
          pattern: '//div[@id="mainBody"]//div//div[@class="sectionblock"]//ul//li//a'
        },
        # This works from MS07-030 until MS13-106 (the last update in 2013)
        # The check is pretty short so if it kicks in too early, it tends to create false positives.
        # So it goes last.
        {
          check:   '//div[@id="mainBody"]//p//strong[contains(text(), "Affected Software")]',
          pattern: '//div[@id="mainBody"]//table//a' 
        }
      ]

    end
  end
end
