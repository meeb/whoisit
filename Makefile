python=/usr/bin/env python3


test:
	echo && PYTHONPATH="${PYTHONPATH}:whoisit" $(python) -m unittest discover -s tests -v
