POS=`expr index "$1" ,`
#echo $POS
#if [ $POS -gt 8 ]a
if [[ $1 == *,* ]] 
then
	echo $POS
	IFS=', ' read -r -a array <<< "$1"
	for elem in "${array[@]}"
		do
			sudo ipset add WL $elem
		done
else
		sudo ipset add WL $1
fi
