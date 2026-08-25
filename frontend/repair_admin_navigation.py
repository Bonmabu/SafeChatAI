from pathlib import Path

path = Path("src/AdminSOC.jsx")
text = path.read_text(encoding="utf-8-sig")

# Add navigation helper after component declaration
needle = 'export default function AdminSOC() {\n'
replacement = '''export default function AdminSOC() {

  const navigateAdmin = (target) => {
    const element = document.getElementById(target);

    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }
  };

'''
if needle in text and "const navigateAdmin" not in text:
    text = text.replace(needle, replacement, 1)

# Give the existing major sections navigation targets
text = text.replace(
    '<section className="admin-section">',
    '<section id="soc-platform" className="admin-section">',
    1
)

# Second admin-section = identity/user operations
first = text.find('<section id="soc-platform"')
second = text.find('<section className="admin-section">', first + 1)

if second != -1:
    text = (
        text[:second]
        + text[second:].replace(
            '<section className="admin-section">',
            '<section id="identity-operations" className="admin-section">',
            1
        )
    )

# Make Open SOC button functional
text = text.replace(
    '<button className="admin-action-button" type="button">\n                  Open SOC\n                </button>',
    '''<button
                  className="admin-action-button"
                  type="button"
                  onClick={() => navigateAdmin("soc-platform")}
                >
                  Open SOC
                </button>''',
    1
)

# Make Audit Center button functional
text = text.replace(
    '<button className="admin-action-button" type="button">\n                  View Logs\n                </button>',
    '''<button
                  className="admin-action-button"
                  type="button"
                  onClick={() => navigateAdmin("admin-audit-center")}
                >
                  View Logs
                </button>''',
    1
)

# Make upgrade button functional
text = text.replace(
    '<button className="admin-upgrade-button" type="button">\n                Explore Enterprise Upgrade\n              </button>',
    '''<button
                className="admin-upgrade-button"
                type="button"
                onClick={() => navigateAdmin("enterprise-upgrade")}
              >
                Explore Enterprise Upgrade
              </button>''',
    1
)

# Add an audit target to the Audit card
audit_marker = '<div className="admin-control-card">\n            <div className="admin-control-card-header">\n              <div className="admin-control-icon">📜</div>'

if audit_marker in text:
    text = text.replace(
        audit_marker,
        '<div id="admin-audit-center" className="admin-control-card">\n            <div className="admin-control-card-header">\n              <div className="admin-control-icon">📜</div>',
        1
    )

# Add upgrade target to upgrade card
text = text.replace(
    '<div className="admin-control-card admin-upgrade-card">',
    '<div id="enterprise-upgrade" className="admin-control-card admin-upgrade-card">',
    1
)

# Make control buttons keyboard-accessible
text = text.replace(
    'onClick={() => toggleControl("auditLogging")}',
    'onClick={() => toggleControl("auditLogging")}',
    1
)

# Ensure file has normal UTF-8 and LF line endings
text = text.replace("\r\n", "\n")
path.write_text(text, encoding="utf-8", newline="\n")

print("Admin SOC navigation repaired.")
