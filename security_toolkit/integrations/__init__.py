"""External tool integration adapters.

Each adapter detects whether its tool is installed, verifies the version,
executes only supported operations, captures output, and normalizes results
into the toolkit's schema. Adapters degrade gracefully when the tool is absent.
"""
