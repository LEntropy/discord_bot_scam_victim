.PHONY: help demo test app install clean

help:
	@echo "make install  - 의존성 설치(테스트/데모용)"
	@echo "make demo      - 샌드박스 시연 (취약 vs 방어)"
	@echo "make test      - pytest 실행"
	@echo "make app       - FastAPI 라이브 데모 (http://127.0.0.1:8000)"

install:
	python3 -m pip install -r requirements.txt

demo:
	python3 demo.py

test:
	python3 -m pytest -q

app:
	python3 app.py

clean:
	rm -rf .pytest_cache **/__pycache__ __pycache__
