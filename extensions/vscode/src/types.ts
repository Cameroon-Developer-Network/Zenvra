/**
 * Zenvra API Types for VS Code Extension
 */

export interface AiConfig {
  provider: string;
  apiKey: string;
  model: string;
  endpoint?: string;
}

export interface ScanRequest {
  code: string;
  language: string;
  engines?: string[];
  aiConfig?: AiConfig;
}

export interface Finding {
  id: string;
  engine: 'sast' | 'sca' | 'secrets' | 'ai_code';
  cve_id?: string;
  cwe_id?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  explanation: string;
  vulnerable_code: string;
  fixed_code: string;
  line_start: number;
  line_end: number;
  file_path?: string;
}
