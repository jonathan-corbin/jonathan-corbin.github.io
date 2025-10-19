---
layout: default
title: Insane
permalink: /categories/insane/
---

# Insane
{% for post in site.categories.Insane %}
- [ {{ post.date | date: "%Y-%m-%d" }} ] [{{ post.title }}]({{ post.url }})
{% endfor %}
