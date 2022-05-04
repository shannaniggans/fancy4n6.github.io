---
permalink: /tools/
layout: default
title: "Home"
---


<div class="posts">
  {% for post in site.categories['Tools'] %}
      <h2>
          <a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a>
      </h2>
      <div>
        <p class="post_date">{{ post.date | date: "%B %e, %Y" }}</p>
      </div>
      <div class="entry">
        {{ post.excerpt }}
      </div>
  {% endfor %}
</div>