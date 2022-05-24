---
layout: default
title: "Home"
permalink: /
---




<div id="intro">
        <h2>
          {{ site.description }}
        </h2>

</div>


<div class="latest-posts">
<h1>Latest Posts</h1>

<ul>
    {% for post in site.posts %}
    <li><h2><a href="{{ post.url }}">{{ post.title }}</a></h2>
        {%- assign date_format = site.minima.date_format | default: '%b %-d, %Y' -%}
        <h6>{{ post.date | date: date_format }}<br>
            {% include reading-time.html %}</h6>
        {{ post.excerpt }}
    </li>
    {% endfor %}
</ul>
</div>

<!-- Add in the Tag cloud -->
