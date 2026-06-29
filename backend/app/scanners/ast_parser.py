"""
AST Parser
Extracts structural information from Python source files using the `ast` module.
This is deterministic — no LLM involved. Just walking the syntax tree.
"""

import ast
from app.utils.logger import get_logger

logger = get_logger("ast_parser")

# Function call names that indicate a database query is happening
DB_QUERY_INDICATORS = {'execute', 'executemany', 'raw', 'query'}

# Function call names that indicate user input is entering the program
INPUT_SOURCE_INDICATORS = {'get', 'getlist'}  # e.g. request.args.get(), request.form.get()

# Function call names that are inherently dangerous if fed untrusted input
DANGEROUS_CALLS = {'eval', 'exec', 'system', 'popen', 'loads', 'load'}


def _get_call_name(node: ast.Call) -> str:
    """
    Extract the function/method name being called.
    Handles both simple calls (eval(x)) and attribute calls (os.system(x)).
    """
    if isinstance(node.func, ast.Name):
        return node.func.id
    elif isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def parse_python_file(file_path: str) -> dict:
    """
    Parse a single Python file and extract its structure.

    Args:
        file_path: Path to the .py file

    Returns:
        Dict with functions, imports, and flagged danger points.
        Returns a dict with "error" key if the file has a syntax error
        (don't crash the whole scan over one bad file).
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source = f.read()
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as e:
        logger.warning(f"Syntax error parsing {file_path}: {str(e)}")
        return {"file": file_path, "error": f"SyntaxError: {str(e)}"}
    except Exception as e:
        logger.warning(f"Failed to read/parse {file_path}: {str(e)}")
        return {"file": file_path, "error": str(e)}

    result = {
        "file": file_path,
        "functions": [],
        "imports": [],
        "dangerous_calls": []
    }

    # Extract imports (top-level, anywhere in file)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                result["imports"].append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                result["imports"].append(f"{module}.{alias.name}")

    # Extract function definitions and analyze their bodies
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func_info = {
                "name": node.name,
                "line": node.lineno,
                "args": [arg.arg for arg in node.args.args],
                "has_db_query": False,
                "has_user_input": False,
                "calls": []
            }

            # Walk inside this function's body for calls
            for inner_node in ast.walk(node):
                if isinstance(inner_node, ast.Call):
                    call_name = _get_call_name(inner_node)
                    if not call_name:
                        continue

                    func_info["calls"].append({"name": call_name, "line": inner_node.lineno})

                    if call_name in DB_QUERY_INDICATORS:
                        func_info["has_db_query"] = True

                    if call_name in INPUT_SOURCE_INDICATORS:
                        func_info["has_user_input"] = True

                    if call_name in DANGEROUS_CALLS:
                        result["dangerous_calls"].append({
                            "function": node.name,
                            "call": call_name,
                            "line": inner_node.lineno
                        })

            result["functions"].append(func_info)

    return result