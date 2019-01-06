<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true; section>
    <#if section = "title">
        WEBAUTHN
    <#elseif section = "header">
        WEBAUTHN
    <#elseif section = "form">
        <script>
		const $ = q => {
		  return document.querySelector(q);
		};

		const show = q => {
		  $(q).style.display = 'block';
		};

		const hide = q => {
		  $(q).style.display = 'none';
		};

		const isChecked = q => {
		  return $(q).checked;
		};

		const onClick = (q, func) => {
		  $(q).addEventListener('click', func);
		};		


		const requestOptions = {};
		parameters = ${request?no_esc};
		_parameters = ${request?no_esc};

		requestOptions.challenge = strToBin(parameters.challenge);
		//if ($('#customTimeout').value != '') {
		//  requestOptions.timeout = $('#customTimeout').value;
		//}

		if ('rpId' in parameters) {
		  requestOptions.rpId = parameters.rpId;
		}
		if ('allowCredentials' in parameters) {
		  requestOptions.allowCredentials = credentialListConversion(parameters.allowCredentials);
		}
		//if ($('#userVerification').value != "none") {
		//  requestOptions.userVerification = $('#userVerification').value;
		//}

		console.log(requestOptions);

		navigator.credentials.get({
		  "publicKey": requestOptions
		}).then(assertion => {

			const publicKeyCredential = {};

			if ('id' in assertion) {
			  publicKeyCredential.id = assertion.id;
			}
			if ('type' in assertion) {
			  publicKeyCredential.type = assertion.type;
			}
			if ('rawId' in assertion) {
			  publicKeyCredential.rawId = binToStr(assertion.rawId);
			}
			if (!assertion.response) {
			  throw "Get assertion response lacking 'response' attribute";
			}

			const _response = assertion.response;

			publicKeyCredential.response = {
			  clientDataJSON:     binToStr(_response.clientDataJSON),
			  authenticatorData:  binToStr(_response.authenticatorData),
			  signature:          binToStr(_response.signature),
			  userHandle:         binToStr(_response.userHandle)
			};

			document.getElementById('data').value = JSON.stringify(publicKeyCredential);
			document.getElementById('session').value = _parameters.session.id;
			document.getElementById('kc-u2f-login-form').submit();
		  }).catch(err => {
			console.log(err.toString());
			alert("An error occurred during Assertion request " + err.toString());
		  });

		function strToBin(str) {
			return Uint8Array.from(atob(str), c => c.charCodeAt(0));
		}

		function binToStr(bin) {
			return btoa(new Uint8Array(bin).reduce((s, byte) => s + String.fromCharCode(byte), ''));
		}

		function credentialListConversion(list) {

		  return list.map(item => {
			const cred = {
			  type: item.type,
			  id: strToBin(item.id)
			};
			if (item.transports) {
			  cred.transports = list.transports;
			}
			return cred;
		  });
		}

		function novoRegistro() {
			document.getElementById('data').value = "new-register";
			document.getElementById('kc-u2f-login-form').submit();
		}

        </script>

        <p>LOGIN WEBAUTHN</p>
				
	<p>
		<a href='javascript:novoRegistro()'>New Register</a>
	</p>
		
        <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-u2f-login-form" method="post">
            <input type="hidden" name="data" id="data"/>
            <input type="hidden" name="session" id="session"/>

            <input style="display:none;" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
        </form>
    </#if>
</@layout.registrationLayout>
