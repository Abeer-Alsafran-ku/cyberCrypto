server:
	python3 server.py
client:
	python3 client.py
mitm:
	python3 attacks/mitm.py
replay:
	python3 attacks/replay.py
tamper:
	python3 attacks/tamper.py
push:
	git add .; git commit; git push
