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

		const makeCredentialOptions = {};
		
		options = ${request};
		_options = ${request};

		makeCredentialOptions.rp = options.rp;
		makeCredentialOptions.user = options.user;
		makeCredentialOptions.user.id = strToBin(options.user.id);
		makeCredentialOptions.challenge = strToBin(options.challenge);
		makeCredentialOptions.pubKeyCredParams = options.pubKeyCredParams;

		// Optional parameters
		//if ($('#customTimeout').value != '') {
		//  makeCredentialOptions.timeout = $('#customTimeout').value;
		//}

		if ('excludeCredentials' in options) {
		  makeCredentialOptions.excludeCredentials = credentialListConversion(options.excludeCredentials);
		}
		if ('authenticatorSelection' in options) {
		  makeCredentialOptions.authenticatorSelection = options.authenticatorSelection;
		}
		if ('attestation' in options) {
		  makeCredentialOptions.attestation = options.attestation;
		}
		if ('extensions' in options) {
		  makeCredentialOptions.extensions = options.extensions;
		}
		console.log(makeCredentialOptions);


		navigator.credentials.create({
		  "publicKey": makeCredentialOptions
		}).then(attestation => {
			const publicKeyCredential = {};

			if ('id' in attestation) {
			  publicKeyCredential.id = attestation.id;
			}
			if ('type' in attestation) {
			  publicKeyCredential.type = attestation.type;
			}
			if ('rawId' in attestation) {
			  publicKeyCredential.rawId = binToStr(attestation.rawId);
			}
			if (!attestation.response) {
			  showErrorMsg("Make Credential response lacking 'response' attribute");
			}

			const response = {};
			response.clientDataJSON = binToStr(attestation.response.clientDataJSON);
			response.attestationObject = binToStr(attestation.response.attestationObject);
			publicKeyCredential.response = response;

			var form = document.getElementById('kc-u2f-settings-form');
			var data = document.getElementById('data');
			var session = document.getElementById('session');

			data.value=JSON.stringify(publicKeyCredential);
			session.value=_options.session.id;
			form.submit();

		  }).catch(err => {
			console.log(err.toString());
			alert("An error occurred during Make Credential operation: " + err.toString());
		  });


		function strToBin(str) {
			return Uint8Array.from(atob(str), c => c.charCodeAt(0));
		}

		function binToStr(bin) {
			return btoa(new Uint8Array(bin).reduce((s, byte) => s + String.fromCharCode(byte), ''));
		}
        </script>

        <p>REGISTRO WEBAUTHN</p>

        <form action="${url.loginAction}" class="${properties.kcFormClass!}" id="kc-u2f-settings-form" method="post">
            <input type="hidden" name="data" id="data"/>
            <input type="hidden" name="session" id="session"/>

            <input style="display:none;" class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doSubmit")}"/>
        </form>
    </#if>
</@layout.registrationLayout>
