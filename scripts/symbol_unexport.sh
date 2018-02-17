#!/bin/bash

rm $2

for i in `nm -g $1 | grep ' T ' | awk '{print $3}'`;
do
	echo "$i $3_$i" >> $2
done

for i in `nm -g $1 | grep ' D ' | awk '{print $3}'`;
do
	echo "$i $3_$i" >> $2
done

objcopy --redefine-syms=$2 $1
