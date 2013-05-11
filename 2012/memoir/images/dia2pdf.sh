#!/bin/sh
## the filename without the extension .dia
#ROOT=${1:0:${#1}-4}
CHEMIN="/home/backup/Documents/CeFri/LicenceCeFri/Memoire/Projet\ de\ memoire/latex/" 

TMPFILE=$(tempfile)
#cd $CHEMIN && dia -e $TMPFILE -t eps $1.dia && ps2pdf -dEPSCrop $TMPFILE $1.pdf
dia -e $TMPFILE -t eps $1.dia && ps2pdf -dEPSCrop $TMPFILE $1.pdf
