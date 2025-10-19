---
layout: default
title: Easy
permalink: /categories/easy/
---

# Easy
{% for post in site.categories.Easy %}
- [ {{ post.date | date: "%Y-%m-%d" }} ] [{{ post.title }}]({{ post.url }})
{% endfor %}
