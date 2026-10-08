#!/bin/bash
# The runner's job-started hook. Bounded, and fails closed: any non-zero exit,
# including the timeout's, fails the job before its first step.
exec /usr/bin/timeout --kill-after=5 30 /usr/bin/python3 -I /usr/lib/tos-ci-guest/admission.py
