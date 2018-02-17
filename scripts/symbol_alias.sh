#!/bin/bash

objcopy --redefine-sym $2=$3 $1 
