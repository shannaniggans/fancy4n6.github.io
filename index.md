---
layout: default
title: "Home"
permalink: /
---

<h1>Latest Posts</h1>

<ul>
    {% for post in site.posts %}
    <li><h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        {{ post.date }}
        {{ post.excerpt }}
    </li>
    {% endfor %}
</ul>
