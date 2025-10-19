---
layout: default
title: Windows
permalink: /categories/windows/
---

# Windows
{% for post in site.categories.Windows %}
- [ {{ post.date | date: "%Y-%m-%d" }} ] [{{ post.title }}]({{ post.url }})
{% endfor %}
