
<!DOCTYPE HTML>
<html>
	<head>
		<title>Frida CodeShare</title>
		<meta charset="utf-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
		<link rel="shortcut icon" type="image/png" href="/static/images/favicon.ico"/>
    <link rel="stylesheet" href="/static/css/main.css" />
    <!--[if lte IE 8]><script src="/static/js/ie/html5shiv.js"></script><![endif]-->
		<!--[if lte IE 9]><link rel="stylesheet" href="/static/css/ie9.css" /><![endif]-->
		<!--[if lte IE 8]><link rel="stylesheet" href="/static/css/ie8.css" /><![endif]-->

    
	</head>
	<body>
  <!-- Wrapper -->
  <div id="wrapper">
     <!-- Main -->
    <div id="main">
      <div class="inner">

        <!-- Header -->
        <header id="header">
  <ul class="icons">
    <li><a href="/" class="logo">Frida CodeShare</a></li>
    <li><a href="https://twitter.com/fridadotre" class="icon fa-twitter"><span class="label">Twitter</span></a></li>
    <li><a href="https://github.com/frida" class="icon fa-github"><span class="label">Github</span></a></li>
  </ul>

  <div class="header-right">
    
      <div class="user-options">
        <a href="/login/auth0" class="logo right">Log In</a>
      </div>
    

    <form class="search" method="get" action="/search/">
      <input type="text" name="query" id="query" placeholder="Search" />
    </form>
  </div>
</header>



        

  <!-- Section -->
  <section id="editProject">
    <h2>Project: Universal Android SSL Pinning Bypass with Frida</h2>

    <form id="new-project-form" method="post" action="#"><input type="hidden" name="csrfmiddlewaretoken" value="DRqUpP1Rubp3elQCnbaZr223K5X60Na42VlQ7FQr0yGH1vjdbKXqypJR1mMWazUQ">
      <div class="row uniform">
        <div class="12u$ code-info">
          <p>Try this code out now by running  </p>
          <div class="box">
            <pre>$ frida --codeshare pcipolloni/${projectSlug} -f YOUR_BINARY</pre>
          </div>
        </div>

        <!-- Break -->
        <div class="12u$">
          <div @keyup="validateForm" v-model="projectSource" id="editor"></div>
        </div>

        <!-- Break -->
        <div class="12u$">
          <p>Fingerprint: 2a7755acc4c6b292bc214622b6fc10f818be47e1e40800802a6d716ce68e621b</p>
          <p class="error-message" v-model="errorMsg">${errorMsg}</p>
          <ul class="actions">
            
            
            <li><input type="button" class="cancel-button" value="Back"/></li>
          </ul>
        </div>
      </div>
    </form>

  </section>



      </div>
    </div>

    
    

  </div>

    <!-- Scripts -->
    <script src="/static/js/jquery.min.js"></script>
    <script src="/static/js/skel.min.js"></script>
    <script src="/static/js/util.js"></script>
    <!--[if lte IE 8]><script src="/static/js/ie/respond.min.js"></script><![endif]-->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/2.3.3/vue.min.js"></script>
    <script src="/static/js/main.js"></script>

    <script>
      function csrfSafeMethod(method) {
          // these HTTP methods do not require CSRF protection
          return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
      }
      $.ajaxSetup({
          beforeSend: function(xhr, settings) {
              if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                  xhr.setRequestHeader("X-CSRFToken", jQuery("[name=csrfmiddlewaretoken]").val());
              }
          },
          contentType: "application/json; charset=utf-8"
      });
    </script>

  <!-- Auth0 Lock removed - using server-side authentication -->

    
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vue/2.3.3/vue.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.2.6/ace.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/js-beautify/1.6.14/beautify.min.js"></script>
  <script>

      var app = new Vue({
          el: '#editProject',
          delimiters: ['${', '}'],
          data: {
              isValid: false,
              projectName: "Universal Android SSL Pinning Bypass with Frida",
              projectSlug: "universal\u002Dandroid\u002Dssl\u002Dpinning\u002Dbypass\u002Dwith\u002Dfrida",
              projectCategory: "Misc",
              projectSource: "/* \u000A   Android SSL Re\u002Dpinning frida script v0.2 030417\u002Dpier \u000A\u000A   $ adb push burpca\u002Dcert\u002Dder.crt /data/local/tmp/cert\u002Dder.crt\u000A   $ frida \u002DU \u002Df it.app.mobile \u002Dl frida\u002Dandroid\u002Drepinning.js \u002D\u002Dno\u002Dpause\u000A\u000A   https://techblog.mediaservice.net/2017/07/universal\u002Dandroid\u002Dssl\u002Dpinning\u002Dbypass\u002Dwith\u002Dfrida/\u000A   \u000A   UPDATE 20191605: Fixed undeclared var. Thanks to @oleavr and @ehsanpc9999 !\u000A*/\u000A\u000AsetTimeout(function(){\u000A    Java.perform(function (){\u000A    \u0009console.log(\u0022\u0022)\u003B\u000A\u0009    console.log(\u0022[.] Cert Pinning Bypass/Re\u002DPinning\u0022)\u003B\u000A\u000A\u0009    var CertificateFactory \u003D Java.use(\u0022java.security.cert.CertificateFactory\u0022)\u003B\u000A\u0009    var FileInputStream \u003D Java.use(\u0022java.io.FileInputStream\u0022)\u003B\u000A\u0009    var BufferedInputStream \u003D Java.use(\u0022java.io.BufferedInputStream\u0022)\u003B\u000A\u0009    var X509Certificate \u003D Java.use(\u0022java.security.cert.X509Certificate\u0022)\u003B\u000A\u0009    var KeyStore \u003D Java.use(\u0022java.security.KeyStore\u0022)\u003B\u000A\u0009    var TrustManagerFactory \u003D Java.use(\u0022javax.net.ssl.TrustManagerFactory\u0022)\u003B\u000A\u0009    var SSLContext \u003D Java.use(\u0022javax.net.ssl.SSLContext\u0022)\u003B\u000A\u000A\u0009    // Load CAs from an InputStream\u000A\u0009    console.log(\u0022[+] Loading our CA...\u0022)\u000A\u0009    var cf \u003D CertificateFactory.getInstance(\u0022X.509\u0022)\u003B\u000A\u0009    \u000A\u0009    try {\u000A\u0009    \u0009var fileInputStream \u003D FileInputStream.$new(\u0022/data/local/tmp/cert\u002Dder.crt\u0022)\u003B\u000A\u0009    }\u000A\u0009    catch(err) {\u000A\u0009    \u0009console.log(\u0022[o] \u0022 + err)\u003B\u000A\u0009    }\u000A\u0009    \u000A\u0009    var bufferedInputStream \u003D BufferedInputStream.$new(fileInputStream)\u003B\u000A\u0009  \u0009var ca \u003D cf.generateCertificate(bufferedInputStream)\u003B\u000A\u0009    bufferedInputStream.close()\u003B\u000A\u000A\u0009\u0009var certInfo \u003D Java.cast(ca, X509Certificate)\u003B\u000A\u0009    console.log(\u0022[o] Our CA Info: \u0022 + certInfo.getSubjectDN())\u003B\u000A\u000A\u0009    // Create a KeyStore containing our trusted CAs\u000A\u0009    console.log(\u0022[+] Creating a KeyStore for our CA...\u0022)\u003B\u000A\u0009    var keyStoreType \u003D KeyStore.getDefaultType()\u003B\u000A\u0009    var keyStore \u003D KeyStore.getInstance(keyStoreType)\u003B\u000A\u0009    keyStore.load(null, null)\u003B\u000A\u0009    keyStore.setCertificateEntry(\u0022ca\u0022, ca)\u003B\u000A\u0009    \u000A\u0009    // Create a TrustManager that trusts the CAs in our KeyStore\u000A\u0009    console.log(\u0022[+] Creating a TrustManager that trusts the CA in our KeyStore...\u0022)\u003B\u000A\u0009    var tmfAlgorithm \u003D TrustManagerFactory.getDefaultAlgorithm()\u003B\u000A\u0009    var tmf \u003D TrustManagerFactory.getInstance(tmfAlgorithm)\u003B\u000A\u0009    tmf.init(keyStore)\u003B\u000A\u0009    console.log(\u0022[+] Our TrustManager is ready...\u0022)\u003B\u000A\u000A\u0009    console.log(\u0022[+] Hijacking SSLContext methods now...\u0022)\u000A\u0009    console.log(\u0022[\u002D] Waiting for the app to invoke SSLContext.init()...\u0022)\u000A\u000A\u0009   \u0009SSLContext.init.overload(\u0022[Ljavax.net.ssl.KeyManager\u003B\u0022, \u0022[Ljavax.net.ssl.TrustManager\u003B\u0022, \u0022java.security.SecureRandom\u0022).implementation \u003D function(a,b,c) {\u000A\u0009   \u0009\u0009console.log(\u0022[o] App invoked javax.net.ssl.SSLContext.init...\u0022)\u003B\u000A\u0009   \u0009\u0009SSLContext.init.overload(\u0022[Ljavax.net.ssl.KeyManager\u003B\u0022, \u0022[Ljavax.net.ssl.TrustManager\u003B\u0022, \u0022java.security.SecureRandom\u0022).call(this, a, tmf.getTrustManagers(), c)\u003B\u000A\u0009   \u0009\u0009console.log(\u0022[+] SSLContext initialized with our custom TrustManager!\u0022)\u003B\u000A\u0009   \u0009}\u000A    })\u003B\u000A},0)\u003B",
              projectDesc: "Android SSL Re\u002DPinning, more information can be found here https://techblog.mediaservice.net/2017/07/universal\u002Dandroid\u002Dssl\u002Dpinning\u002Dbypass\u002Dwith\u002Dfrida/",
              errorMsg: "",
              projectUUID: "17022cb6-e2f7-4c87-8986-d17b5d1f3def",
              likeButtonDisabled: false,
      
              likeButtonLoading: false,
      

          },
          methods: {
              validateForm: function(){
                  return
              },
              updateProject: function(){
                  return
              },
              sendLike: function(){
                  var that = this;
                  this.likeButtonLoading = true;
                  $.post("/api/like/", JSON.stringify({project_uuid: that.projectUUID}))
                      .then(function success(result) {
                          that.likeButtonDisabled = true;
                      },
                      function error(){
                          that.errorMsg = "Unable to like this project! Support has been notified. Sorry 😓"
                      })
                      .always(function(){
                          that.likeButtonLoading = false;
                      });

                  return false
              }
          },
          watch: {
              projectName: function(val, oldval){
                  if (val.match(/[^a-zA-Z0-9\-\s]/gi)){
                      this.projectName = this.projectName.replace(/[^a-zA-Z0-9\-\s]/gi, '')
                  }
                  this.projectSlug = this.projectName.replace(/\s/gi, '-').toLowerCase()
              }
          }
      })

      $('.cancel-button').click(function(){
          window.history.back()
      })

      $('.delete-button').click(function(){
          if(confirm("Are you sure you want to remove the project '" + app.projectName + "'? THIS CAN NOT BE UNDONE!")){
              $.ajax({
                  url: "/api/update/pcipolloni/universal-android-ssl-pinning-bypass-with-frida/",
                  type: 'DELETE',
                  success: function(result) {
                      window.location = "/@pcipolloni/"
                  }
              });
          };
      })

      $('.beautify-content').click(function(e){
          e.preventDefault();
          var session = editor.getSession();
          session.setValue(js_beautify(session.getValue()));
      })

      var beautify = ace.require("ace/ext/beautify");
      var editor = ace.edit("editor");
      editor.setTheme("ace/theme/monokai");
      editor.getSession().setMode("ace/mode/javascript");
      editor.setShowPrintMargin(false);
      editor.setReadOnly(true);

      editor.on('change', function(e){
          app.projectSource = editor.getSession().getValue()
          app.validateForm()
      })

      if (app.projectSource){
          editor.getSession().setValue(app.projectSource);
      }


  $(document).ready(function(){

    var heightUpdateFunction = function() {

        // http://stackoverflow.com/questions/11584061/
        var newHeight =
                  editor.getSession().getScreenLength()
                  * editor.renderer.lineHeight
                  + editor.renderer.scrollBar.getWidth();

        $('#editor').height(newHeight.toString() + "px");
        $('#editor-section').height(newHeight.toString() + "px");

        // This call is required for the editor to fix all of
        // its inner structure for adapting to a change in size
        editor.resize();
    };

    // Set initial size to match initial content
    heightUpdateFunction();

    // Whenever a change happens inside the ACE editor, update
    // the size again
    editor.getSession().on('change', heightUpdateFunction);
})

  </script>
  <style>
  #editor {
      min-height: 16rem;
  }
  </style>


	</body>
</html>
