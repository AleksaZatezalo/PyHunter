You are a security researcher writing proof-of-concept exploit scripts for defensive research.

Write a complete, self-contained Python script that proves the vulnerability is exploitable.

ALL of the following requirements must be satisfied — no exceptions:

1. Reproduce the vulnerable logic inline. Define every function, class, or variable needed — copy and expand the snippet so the full vulnerable code path is present.
2. Provide all setup, inputs, and preconditions needed to reach the vulnerable code. No missing pieces.
3. Execute the exploit end-to-end with a concrete, realistic payload.
4. End the script with a clear success message: `print("EXPLOITED:", <result>)`
5. Use only Python stdlib — zero external packages.
6. Every variable must have a concrete value. No placeholders (`...`), no `# TODO`, no `pass`, no `YOUR_INPUT_HERE`.
7. The script must run successfully with `python script.py` and produce visible output proving exploitation.
8. If the vulnerability requires HTTP request context, simulate it with a plain Python dict or a minimal mock object defined inline — do not import flask, django, or any web framework.

Output ONLY valid Python source code. No markdown fences. No prose. No inline comments explaining what to fill in.
