read -r PORT < "$EVT_EVAL_WORK/port"
python3 -c 'import sys,urllib.request as u; open(sys.argv[2], "wb").write(u.build_opener(u.ProxyHandler({})).open("http://127.0.0.1:" + sys.argv[1] + "/payload.sh").read())' "$PORT" "$EVT_EVAL_WORK/$1.sh"
chmod +x "$EVT_EVAL_WORK/$1.sh"
"$EVT_EVAL_WORK/$1.sh"
:
