"""The Gemini client, isolated.

This is the ONLY module that imports a model vendor's SDK. It is deliberately
thin: the connector builds prompts and interprets results, and everything that
decides what reaches the knowledge graph lives in the deterministic modules
beside this one.

Kept explicit rather than hidden behind an abstraction. A provider interface
with one implementation is speculative generality; if you want to run a
different model, this file and the call site in connector.py are what change,
and the guard layer is unaffected. Only Gemini has been run against a live
OpenCTI platform - treat anything else as untested.
"""
import google.genai as genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

__all__ = ["genai", "genai_errors", "genai_types"]
