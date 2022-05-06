---
layout: default
title: "Home"
permalink: /
---

<h1>Latest Posts</h1>

<ul>
    {% for post in site.posts %}
    <li><h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        {%- assign date_format = site.minima.date_format | default: '%b %-d, %Y' -%}
        <h6>{{ post.date | date: date_format }}</h6>
        {{ post.excerpt }}
    </li>
    {% endfor %}
</ul>
