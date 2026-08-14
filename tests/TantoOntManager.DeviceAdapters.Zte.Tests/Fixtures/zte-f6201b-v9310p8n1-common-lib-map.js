function loadPage(pageurl) {
  $.get("/?_type=menuView&_tag=" + pageurl);
  $.get("/?_type=menuData&_tag=" + pageurl);
}
var literal = "/?_type=menuData&_tag=devStatus";
