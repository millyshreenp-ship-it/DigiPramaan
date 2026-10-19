.PHONY: demo test build clean docker-up cli-demo seed

# Run the complete web demo
demo:
	python scripts/seed_demo.py
	python demo.py

# Run CLI terminal demo
cli-demo:
	python demo.py --cli

# Run pytest verification suite
test:
	python -m pytest -v

# Seed sample forensic cases
seed:
	python scripts/seed_demo.py

# Docker one-command run
docker-up:
	docker compose up --build

# Build React frontend
build-frontend:
	cd frontend && npm install && npm run build
