# Contributing to AEGIS

First off, thank you for considering contributing to AEGIS! 🎉

## 🚀 Quick Start

1. **Fork** the repository at [https://github.com/Masriyan/Aegis](https://github.com/Masriyan/Aegis)
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/Aegis.git`
3. **Create a branch**: `git checkout -b feature/amazing-feature`
4. **Make changes** and test them
5. **Commit**: `git commit -m 'Add amazing feature'`
6. **Push**: `git push origin feature/amazing-feature`
7. **Open a Pull Request**

---

## 🧩 Adding a New Module

AEGIS is designed to be modular. Here's how to add your own reconnaissance module:

### Step 1: Create the Function

```python
def my_awesome_module(target: str):
    """Your module description here"""
    result = {"data": [], "error": None}
    
    try:
        # Your reconnaissance logic here
        result["data"] = ["finding1", "finding2"]
    except Exception as e:
        result["error"] = str(e)
    
    return result
```

### Step 2: Register in `run_scan()`

Find the `run_scan()` function and add your module:

```python
run_mod("my_module", "my_module" in selected_services, my_awesome_module, target)
```

### Step 3: Add UI Checkbox in `INDEX_HTML`

Add your module to the appropriate category:

```python
('My Module', 'my_module', 'fa-star'),
```

### Step 4: Add Render Template in `RESULTS_HTML`

```jinja2
{% elif key == 'my_module' %}
  <table>
    <thead><tr><th>Finding</th></tr></thead>
    <tbody>
      {% for item in value.data %}
        <tr><td>{{ item }}</td></tr>
      {% endfor %}
    </tbody>
  </table>
{% endif %}
```

---

## 📋 Code Style Guidelines

| Rule | Example |
|------|---------|
| **Function names** | `snake_case` - `subdomain_takeover_check()` |
| **Constants** | `UPPER_CASE` - `MITRE_MAPPING` |
| **Docstrings** | Required for all functions |
| **Line length** | Max 120 characters |
| **Error handling** | Always catch exceptions, return `{"error": str(e)}` |

---

## 🧪 Testing Your Changes

Before submitting a PR:

```bash
# Syntax check
python -m py_compile aegis.py

# Run the app
python aegis.py

# Test with a safe target
# Navigate to http://127.0.0.1:8080
# Scan https://example.com with your module enabled
```

---

## 📝 Commit Message Format

```
type(scope): short description

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `style` - Code style (formatting, etc.)
- `refactor` - Code restructuring
- `test` - Adding tests
- `chore` - Maintenance tasks

**Examples:**
```
feat(modules): add DNSSEC validation module
fix(crawler): handle timeout on slow pages
docs(readme): update installation instructions
```

---

## 🎯 What We're Looking For

### ✅ High Priority
- [ ] New reconnaissance modules
- [ ] Bug fixes
- [ ] Performance improvements
- [ ] Documentation updates
- [ ] Test coverage

### 💡 Ideas Welcome
- Additional OSINT integrations
- Export format options (STIX, TAXII)
- Visualization improvements
- CI/CD pipeline setup

---

## ⚠️ Important Notes

1. **Security**: Never commit API keys or secrets
2. **Ethics**: All modules must respect legal boundaries
3. **Dependencies**: Minimize external dependencies
4. **Backwards compatibility**: Don't break existing functionality

---

## 🤝 Code of Conduct

- Be respectful and inclusive
- Provide constructive feedback
- Help others learn and grow
- Focus on what is best for the community

---

## 💬 Need Help?

- 📫 Open an [Issue](https://github.com/Masriyan/Aegis/issues)
- 💬 Start a [Discussion](https://github.com/Masriyan/Aegis/discussions)

---

<p align="center">
  <strong>Thank you for making AEGIS better! 🛡️</strong>
</p>
