# Invoke-Kape
Remote [KAPE](https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape) execution using PowerShell.

## Details
Invoke-Kape will allow you to build a kapecollector.zip package full of your analysis tools and deploy this to a remote machine where collection and analysis will be performed, compressed, and copied back to the specified save location for review.

The kape collector contents are not included and must be obtained from their source. For my use I have minimized what I want to collect for my environment and narrowed down the available commands and what modules and binaries to be included. You can gather this information from the $CollectCommand variables and adjust for your collector package.

## Usage
Invoke-Kape -ComputerName Win10Desktop -Collect Basic
