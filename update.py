import os

def update():
    # 1. db_manager.py
    with open("db_manager.py", "r", encoding="utf-8-sig") as f: c = f.read()
    if "change_user_plan" not in c:
        c = c.replace("def upgrade_user_plan", "def change_user_plan(username, new_plan):\n    conn = get_db()\n    try:\n        conn.execute(\"UPDATE users SET plan = ? WHERE username = ?\", (new_plan, username))\n        conn.commit()\n    finally:\n        conn.close()\n\ndef upgrade_user_plan")
        with open("db_manager.py", "w", encoding="utf-8-sig") as f: f.write(c)

    # 2. translations.py
    with open("translations.py", "r", encoding="utf-8-sig") as f: c = f.read()
    if "profile.billing" not in c:
        c = c.replace('"profile.settings": "Настройки",', '"profile.settings": "Настройки", "profile.billing": "Подписка", "profile.billing_title": "Ваш тариф", "profile.billing_current": "Текущий план", "profile.billing_btn": "Выбрать тариф", "profile.billing_contact": "Связаться",')
        c = c.replace('"profile.settings": "Settings",', '"profile.settings": "Settings", "profile.billing": "Billing", "profile.billing_title": "Your plan", "profile.billing_current": "Current plan", "profile.billing_btn": "Choose plan", "profile.billing_contact": "Contact us",')
        with open("translations.py", "w", encoding="utf-8-sig") as f: f.write(c)

    # 3. app.py
    with open("app.py", "r", encoding="utf-8-sig") as f: c = f.read()
    if "change_plan" not in c:
        c = c.replace("if __name__ == '__main__':", "@app.route('/api/change_plan', methods=['POST'])\ndef api_change_plan():\n    if 'username' not in session: return jsonify({\"error\": \"No auth\"}), 401\n    new_plan = request.get_json().get('plan')\n    if new_plan not in ['free', 'pro', 'startup', 'team', 'enterprise']: return jsonify({\"error\": \"Bad plan\"}), 400\n    db_manager.change_user_plan(session['username'], new_plan)\n    return jsonify({\"status\": \"success\", \"message\": \"Plan changed\"})\n\nif __name__ == '__main__':")
        with open("app.py", "w", encoding="utf-8-sig") as f: f.write(c)

    # 4. profile.html
    with open("templates/profile.html", "r", encoding="utf-8-sig") as f: c = f.read()
    if "tab-billing" not in c:
        c = c.replace('<button class="nav-btn" onclick="openTab(event, \'tab-settings\')">', '<button class="nav-btn" onclick="openTab(event, \'tab-billing\')"><i class="fa-solid fa-credit-card"></i> {{ t(\'profile.billing\') }}</button>\n                <button class="nav-btn" onclick="openTab(event, \'tab-settings\')">')
        
        billing_html = """<div id="tab-billing" class="tab-content">
<h2><i class="fa-solid fa-credit-card"></i> {{ t('profile.billing') }}</h2>
<p style="color: var(--text-muted);">{{ t('profile.billing_title') }}: <span class="badge" style="background: var(--primary); color: white; font-size: 14px;">{{ user['plan'] | upper }}</span></p>
<div class="pricing-grid-4" style="margin-top: 30px;">
    <div class="pricing-card {% if user['plan'] == 'free' %}popular{% endif %}" style="padding: 20px;">
        <h3>Free</h3><div class="price">0 <span>BYN</span></div>
        {% if user['plan'] != 'free' %}<button class="btn-pricing outline" onclick="changePlan('free')">{{ t('profile.billing_btn') }}</button>{% endif %}
    </div>
    <div class="pricing-card {% if user['plan'] == 'pro' %}popular{% endif %}" style="padding: 20px;">
        <h3>Pro</h3><div class="price">49 <span>BYN</span></div>
        {% if user['plan'] != 'pro' %}<button class="btn-pricing primary" onclick="changePlan('pro')">{{ t('profile.billing_btn') }}</button>{% endif %}
    </div>
    <div class="pricing-card {% if user['plan'] == 'startup' %}popular{% endif %}" style="padding: 20px;">
        <h3>Startup</h3><div class="price">99 <span>BYN</span></div>
        {% if user['plan'] != 'startup' %}<button class="btn-pricing outline" onclick="changePlan('startup')">{{ t('profile.billing_btn') }}</button>{% endif %}
    </div>
    <div class="pricing-card {% if user['plan'] == 'team' %}popular{% endif %}" style="padding: 20px;">
        <h3>Team</h3><div class="price">149 <span>BYN</span></div>
        {% if user['plan'] != 'team' %}<button class="btn-pricing outline" onclick="changePlan('team')">{{ t('profile.billing_btn') }}</button>{% endif %}
    </div>
</div>
</div>"""
        c = c.replace('<div id="tab-settings" class="tab-content">', billing_html + '\n            <div id="tab-settings" class="tab-content">')
        c = c.replace("async function updateEmail() {", "async function changePlan(plan) {\n            if (!confirm(\"Сменить тариф на \" + plan.toUpperCase() + \"?\")) return;\n            const res = await fetch('/api/change_plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ plan: plan }) });\n            const data = await res.json();\n            if (data.error) return alert(data.error);\n            alert(data.message);\n            location.reload();\n        }\n\n        async function updateEmail() {")
        with open("templates/profile.html", "w", encoding="utf-8-sig") as f: f.write(c)

    print("OK")

update()