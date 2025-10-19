---
layout: default
title: Medium
permalink: /categories/medium/
---

# Medium
{% for post in site.categories.Medium %}
- [ {{ post.date | date: "%Y-%m-%d" }} ] [{{ post.title }}]({{ post.url }})
{% endfor %}
