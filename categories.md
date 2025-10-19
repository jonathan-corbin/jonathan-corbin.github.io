---
layout: default
title: Categories
permalink: /categories/
---

# Categories

{% assign cats = site.categories | sort %}
<ul>
{% for cat in cats %}
  <li>
    <a href="/categories/{{ cat[0] | downcase | replace:' ','-' }}/">
      {{ cat[0] }} ({{ cat[1].size }})
    </a>
  </li>
{% endfor %}
</ul>
