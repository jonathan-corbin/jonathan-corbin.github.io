---
layout: default
title: Linux
permalink: /categories/linux/
---

# Linux
{% for post in site.categories.Linux %}
- [ {{ post.date | date: "%Y-%m-%d" }} ] [{{ post.title }}]({{ post.url }})
{% endfor %}
