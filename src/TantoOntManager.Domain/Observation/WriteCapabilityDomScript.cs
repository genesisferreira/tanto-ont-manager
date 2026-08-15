namespace TantoOntManager.Domain.Observation;

public static class WriteCapabilityDomScript
{
    public const string Source =
        """
        (function(){
          function sensitive(s){
            s=String(s||'');
            return /(pass|pwd|senha|token|challenge|sid|cookie|auth|loid|serial|mac|gponsn|pppoeuser)/i.test(s);
          }
          function attr(el,n){
            try { return el.getAttribute(n)||''; } catch(e){ return ''; }
          }
          function isPwd(el){
            return String(attr(el,'type')||'').toLowerCase()==='password' || sensitive(attr(el,'name')) || sensitive(attr(el,'id'));
          }
          var controls=[];
          var nodes=document.querySelectorAll('input,select,button,textarea,a');
          for(var i=0;i<nodes.length && controls.length<300;i++){
            var el=nodes[i];
            var tag=el.tagName;
            var name=attr(el,'name').slice(0,64);
            var id=attr(el,'id').slice(0,64);
            var type=String(attr(el,'type')||tag).toLowerCase().slice(0,32);
            var hidden=!!el.hidden || type==='hidden';
            try { if(el.style && (el.style.display==='none' || el.style.visibility==='hidden')) hidden=true; } catch(e){}
            var item={tag:tag,name:isPwd(el)?null:name,id:isPwd(el)?null:id,type:type,disabled:!!el.disabled,readOnly:!!el.readOnly,hidden:hidden,options:[],buttonText:null,handler:null,sensitive:isPwd(el)};
            if(!isPwd(el) && tag==='SELECT' && el.options){
              for(var o=0;o<el.options.length && item.options.length<20;o++){
                var ot=String(el.options[o].text||'').replace(/\s+/g,' ').trim().slice(0,32);
                if(ot && !sensitive(ot)) item.options.push(ot);
              }
            }
            if(!isPwd(el) && (tag==='BUTTON' || type==='button' || type==='submit')){
              var txt=String(el.textContent||attr(el,'value')||'').replace(/\s+/g,' ').trim().slice(0,48);
              if(txt && !sensitive(txt)) item.buttonText=txt;
            }
            var oc=attr(el,'onclick');
            var hm=oc.match(/^[A-Za-z_][A-Za-z0-9_]*/);
            if(hm) item.handler=hm[0];
            controls.push(item);
          }
          var menu=[];
          try{
            if(typeof menuTreeJSON!=='undefined' && menuTreeJSON && menuTreeJSON.length){
              (function walk(arr){
                for(var i=0;i<arr.length;i++){
                  var n=arr[i]||{};
                  var label=String(n.name||n.Name||n.id||n.Id||'').slice(0,64);
                  if(label && !sensitive(label)) menu.push(label);
                  var sub=n.subMenu||n.children||n.Child||n.menu;
                  if(Array.isArray(sub)) walk(sub);
                }
              })(menuTreeJSON);
            }
          }catch(e){}
          var footer=false;
          try{
            footer=(window.pageYOffset||document.documentElement.scrollTop||0)+(window.innerHeight||0)>=(Math.max(document.body.scrollHeight,document.documentElement.scrollHeight)-16);
          }catch(e){}
          return JSON.stringify({menu:menu.slice(0,80),footer:footer,controls:controls});
        })();
        """;

    public static bool IsSafe()
    {
        var text = Source;
        return !text.Contains("click(", StringComparison.OrdinalIgnoreCase)
               && !text.Contains("dispatchEvent", StringComparison.OrdinalIgnoreCase)
               && !text.Contains("innerHTML", StringComparison.OrdinalIgnoreCase)
               && !text.Contains(".submit(", StringComparison.OrdinalIgnoreCase)
               && !text.Contains("Apply(", StringComparison.Ordinal)
               && !text.Contains("Save(", StringComparison.Ordinal)
               && !text.Contains("el.value", StringComparison.Ordinal)
               && text.Contains("isPwd(el)", StringComparison.Ordinal)
               && text.Contains("querySelectorAll", StringComparison.Ordinal);
    }
}
