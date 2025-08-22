# ========================================================================================================
#
#    dP        oo          dP         dP    888888ba           oo       dP
#    88                    88         88    88    `8b                   88
#    88        dP .d8888b. 88d888b. d8888P a88aaaa8P' 88d888b. dP .d888b88 .d8888b. .d8888b.
#    88        88 88'  `88 88'  `88   88    88   `8b. 88'  `88 88 88'  `88 88'  `88 88ooood8
#    88        88 88.  .88 88    88   88    88    .88 88       88 88.  .88 88.  .88 88.  ...
#    88888888P dP `8888P88 dP    dP   dP    88888888P dP       dP `88888P8 `8888P88 `88888P'
#                      .88                                                      .88
#                  d8888P                                                   d8888P
#
#    ====================> AuthZ
#
#    Makefile for the project
#    Author: @stephane-segning
#
# ========================================================================================================

# Variable for passing commands like `just build c="app"`
c := ""

# ----------------------------------------------------------

# Initialize the project
init:
	docker compose -p lightbridge-authz build {{c}}

# Show this help
help:
	@just --summary

# Pull the image
pull:
	docker compose -p lightbridge-authz -f compose.yaml pull {{c}}

# Build the project
build: init
	docker compose -p lightbridge-authz -f compose.yaml build {{c}}

# Start the project
up: init
	docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans --build {{c}}

# Start app
up-single app: init
	docker compose -p lightbridge-authz -f compose.yaml up -d --remove-orphans --build {{app}} {{c}}

# Start the project (without rebuild)
img: init
	docker compose -p lightbridge-authz -f compose.yaml images {{c}}

# Start the project (without rebuild)
start: init
	docker compose -p lightbridge-authz -f compose.yaml start {{c}}

# Stop the project
down:
	docker compose -p lightbridge-authz -f compose.yaml down {{c}}

# Destroy the project
destroy:
	docker compose -p lightbridge-authz -f compose.yaml down -v {{c}}

# Stop containers
stop:
	docker compose -p lightbridge-authz -f compose.yaml stop {{c}}

# Restart the project
restart: init
	docker compose -p lightbridge-authz -f compose.yaml stop {{c}}
	docker compose -p lightbridge-authz -f compose.yaml up -d {{c}}

# Show logs
logs:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f {{c}}

# Show app logs
logs-app:
	docker compose -p lightbridge-authz -f compose.yaml logs --tail=100 -f app {{c}}

# Show status
ps:
	docker compose -p lightbridge-authz -f compose.yaml ps {{c}}

# Show stats
stats:
	docker compose -p lightbridge-authz -f compose.yaml stats {{c}}
