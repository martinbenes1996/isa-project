all: manual.pdf

manual.pdf:
	pdflatex manual.tex
	biber manual
	pdflatex manual.tex
	pdflatex manual.tex

.PHONY: clean
clean:
	@echo "Cleaning LaTeX generated files.";\
	rm -f manual.aux manual.bbl manual.bcf manual.blg manual.log manual.run.xml manual.pdf