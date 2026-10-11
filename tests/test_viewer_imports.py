import ast
import importlib
import pytest
from pathlib import Path

def test_viewer_imports():
    app_path = Path(__file__).parent.parent / "viewer" / "app.py"
    tree = ast.parse(app_path.read_text())
    
    missing = []
    
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("forensic."):
                mod = importlib.import_module(node.module)
                for alias in node.names:
                    name = alias.name
                    if not hasattr(mod, name):
                        missing.append(f"Missing '{name}' in module '{node.module}'")
                        
    if missing:
        pytest.fail("\n".join(missing))
        
    import forensic.ingest
    assert hasattr(forensic.ingest, 'verify_items')
