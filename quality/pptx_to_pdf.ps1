# Converts a .pptx to .pdf with PowerPoint. Usage: powershell -ExecutionPolicy Bypass -File quality\pptx_to_pdf.ps1 D:\radar\FINAL_PRESENTATION_v2.pptx
param([string]$Pptx)
$pdf = [System.IO.Path]::ChangeExtension($Pptx, ".pdf")
$pp = New-Object -ComObject PowerPoint.Application
try {
  $p = $pp.Presentations.Open($Pptx, $true, $false, $false)
  $p.SaveAs($pdf, 32)
  "slides: " + $p.Slides.Count
  $p.Close()
} finally { $pp.Quit() }
"saved $pdf"
