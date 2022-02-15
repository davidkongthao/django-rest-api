#!/bin/bash
find . -type f -name "*00*" -exec rm -f {} \;
find . -type f -name "*.pyc" -exec rm -f {} \;
