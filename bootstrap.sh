#!/bin/sh
export FLASK_APP=./app.py
pipenv install
pipenv run flask --debug run -h 0.0.0.0