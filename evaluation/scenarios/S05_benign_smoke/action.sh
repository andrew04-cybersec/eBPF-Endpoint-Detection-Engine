for i in 1 2 3 4 5 6 7 8; do
	case $i in
	1|5) ls "$EVT_EVAL_WORK" > /dev/null ;;
	2|6) cat "$EVT_EVAL_WORK/data.txt" > /dev/null ;;
	3|7) grep alpha "$EVT_EVAL_WORK/data.txt" > /dev/null ;;
	*) date > /dev/null ;;
	esac
	sleep 2.5
done
:
