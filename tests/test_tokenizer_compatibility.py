import ast
import contextlib
import io
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
FILES = ['kg/main_offline.py', 'agent/main_offline.py',
         'ablations/without_kg/offline_runtime.py', 'hybrid_cwe_refine_offline.py',
         'ablations/without_kg/cwe_refine_offline.py']


def apply_actual_patch(relative, base):
    tokenizer = type('Tokenizer', (base,), {})
    module = types.ModuleType('transformers'); module.__path__ = []
    utilities = types.ModuleType('transformers.tokenization_utils')
    utilities.PreTrainedTokenizer = tokenizer
    bases = types.ModuleType('transformers.tokenization_utils_base')
    bases.PreTrainedTokenizerBase = base
    module.PreTrainedTokenizer = tokenizer; module.PreTrainedTokenizerBase = base
    module.tokenization_utils = utilities; module.tokenization_utils_base = bases
    tree = ast.parse((ROOT/relative).read_text(encoding='utf-8-sig'))
    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'patch_transformers_tokenizers']
    if functions:
        nodes = functions
    else:
        nodes = [next(n for n in tree.body if isinstance(n, ast.Try) and 'all_special_tokens_extended' in ast.unparse(n))]
    namespace = {}
    with patch.dict(sys.modules, {'transformers':module, utilities.__name__:utilities, bases.__name__:bases}), contextlib.redirect_stdout(io.StringIO()):
        exec(compile(ast.Module(body=nodes, type_ignores=[]), relative, 'exec'), namespace)
        if functions: namespace['patch_transformers_tokenizers']()
    return tokenizer


class TokenizerCompatibilityTests(unittest.TestCase):
    def test_original_patch_preserves_native_property(self):
        for relative in FILES:
            with self.subTest(file=relative):
                class Base:
                    @property
                    def all_special_tokens_extended(self): return ['native']
                    @property
                    def all_special_tokens(self): return list(self.all_special_tokens_extended)
                original = Base.__dict__['all_special_tokens_extended']
                tokenizer = apply_actual_patch(relative, Base)
                self.assertIs(Base.__dict__['all_special_tokens_extended'], original)
                self.assertEqual(tokenizer().all_special_tokens, ['native'])

    def test_missing_legacy_property_is_still_added(self):
        for relative in FILES:
            with self.subTest(file=relative):
                class Base:
                    all_special_tokens = ['legacy']
                tokenizer = apply_actual_patch(relative, Base)
                self.assertEqual(tokenizer().all_special_tokens_extended, ['legacy'])
