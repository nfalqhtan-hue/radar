# Converts a .docx to .pdf with Word, after updating the table of contents and page fields; also saves the updated .docx.
# Usage: powershell -ExecutionPolicy Bypass -File quality\docx_to_pdf.ps1 D:\radar\FINAL_REPORT_v2.docx
param([string]$Docx)
$pdf = [System.IO.Path]::ChangeExtension($Docx, ".pdf")
$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
try {
  $doc = $word.Documents.Open($Docx)
  foreach ($toc in $doc.TablesOfContents) { $toc.Update() }
  $doc.Fields.Update() | Out-Null
  foreach ($s in $doc.Sections) { foreach ($f in $s.Footers) { $f.Range.Fields.Update() | Out-Null } }
  $doc.Repaginate()
  foreach ($toc in $doc.TablesOfContents) { $toc.UpdatePageNumbers() }
  $doc.Save()
  $doc.ExportAsFixedFormat($pdf, 17)
  "pages: " + $doc.ComputeStatistics(2)
  $doc.Close($false)
} finally { $word.Quit() }
"saved $pdf"
