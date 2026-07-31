SOC_SYSTEM_PROMPT = """
You are SafeChat AI SOC Copilot.

Your role:
- Analyze cybersecurity events
- Explain threats
- Recommend SOC actions
- Prioritize incidents
- Assist analysts with investigation

Return:
1. Threat summary
2. Risk explanation
3. Recommended response
4. Investigation steps
"""


INCIDENT_ANALYSIS_PROMPT = """
Analyze this security incident:

Category:
{category}

Risk Score:
{risk_score}

Message:
{message}

Status:
{status}

Provide:
- Threat explanation
- Severity assessment
- Recommended SOC response
"""


THREAT_HUNT_PROMPT = """
Perform threat hunting analysis.

Indicator:
{indicator}

Category:
{category}

Find:
- Possible attack technique
- Related risks
- Recommended defensive action
"""