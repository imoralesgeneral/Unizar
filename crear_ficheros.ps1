# Itero desde 1 a 100
1..100 | ForEach-Object {
	# Construyo nombre y contenido de los ficheros
	$fileName = "$($_).txt"
	$content = "Test $_"
	# Creo el archivo y escribo el contenido
	Set-Content -Path $fileName -Value $content
}