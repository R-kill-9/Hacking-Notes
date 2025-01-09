# Revealing file hidden information 

## exiftool
**exifTool** is a command-line tool and Perl library used for reading, writing, and manipulating metadata information in various file formats, particularly image and multimedia files. It allows you to extract, modify, and analyze the metadata embedded within these files.

For example, we could use it to extract metadata from a PDF file and check the "creator" field to see if it was created with a potentially vulnerable tool.

# binwalk
**binwalk** is a tool used for analyzing and extracting data from binary files, such as firmware images, executables, and other binary data. Can be very useful for extracting information from images.

# Revealing Pixelated information in a PDF

## Check for Embedded Text in the PDF

- Sometimes pixelated text might still be embedded as text within the PDF. Extract the text to see if the credentials are present.
- **Tools**: Use `pdftotext` or `strings` to extract potential embedded text.

```bash
pdftotext file.pdf -        # Converts PDF content to text in terminal
strings file.pdf | grep -i "password"  # Searches for keywords like "password" or "user"
```

## Use OCR (Optical Character Recognition) Techniques
If the pixelated content isn't text, OCR can sometimes identify characters within pixelated images.

``` bash
pdfimages -png file.pdf output_image
```
## Depix.py
[Depix](https://github.com/spipm/Depix) is a PoC for a technique to recover plaintext from pixelized screenshots.

- **Installation:**
```bash
git clone https://github.com/spipm/Depix
cd Depix
```

- **Usage:**
After obtaining the image form the pdf file using the OCR techniques explained above, the following command:

```bash
python3 depix.py -p /path/to/your/input/image.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o /path/to/your/output.png
```

- **Options**:
	- `-p`: The pixelated input image.
	- `-r`: The reference image with clear text.
	- `-o`: The output image where Depix will save the result.


