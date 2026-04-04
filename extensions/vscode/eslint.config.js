import eslint from '@eslint/js';
import ts from 'typescript-eslint';
import globals from 'globals';

export default ts.config(
	eslint.configs.recommended,
	...ts.configs.recommended,
	{
		languageOptions: {
			globals: {
				...globals.node,
                ...globals.es2021
			}
		},
		rules: {
			'@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
			'@typescript-eslint/no-explicit-any': 'warn',
			'no-console': 'off'
		}
	},
	{
		ignores: ['out/', 'node_modules/', 'dist/']
	}
);
