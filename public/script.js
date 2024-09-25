let currentStep = 1;
const totalSteps = 4;

function showStep(step) {
  for (let i = 1; i <= totalSteps; i++) {
    const stepElement = document.getElementById(`step${i}`);
    stepElement.style.display = i === step ? 'block' : 'none';
  }
}

function nextStep() {
  if (validateStep(currentStep)) {
    if (currentStep < totalSteps) {
      currentStep++;
      showStep(currentStep);
    }
    if (currentStep === totalSteps) {
      displayConfirmation();
    }
  }
}

function prevStep() {
  if (currentStep > 1) {
    currentStep--;
    showStep(currentStep);
  }
}

function validateStep(step) {
  let isValid = true;

  if (step === 1) {
    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const phoneno = document.getElementById('phoneno').value.trim();

    if (!name) {
      alert('Please enter the manager\'s name.');
      isValid = false;
    } else if (!email) {
      alert('Please enter the email.');
      isValid = false;
    } else if (!phoneno) {
      alert('Please enter the phone number.');
      isValid = false;
    }
  } else if (step === 2) {
    const team = document.getElementById('team').value.trim();
    const captain = document.getElementById('captain').value.trim();

    if (!team) {
      alert('Please enter the team name.');
      isValid = false;
    } else if (!captain) {
      alert('Please enter the captain\'s name.');
      isValid = false;
    }
  } else if (step === 3) {
    const tournament = document.getElementById('tournament').value;
    const match = document.getElementById('match').value;

    if (!tournament) {
      alert('Please select a tournament.');
      isValid = false;
    } else if (!match) {
      alert('Please select a match format.');
      isValid = false;
    }
  }

  return isValid;
}

function displayConfirmation() {
  const name = document.getElementById('name').value;
  const email = document.getElementById('email').value;
  const phoneno = document.getElementById('phoneno').value;
  const team = document.getElementById('team').value;
  const captain = document.getElementById('captain').value;
  const tournament = document.getElementById('tournament').value;
  const match = document.getElementById('match').value;

  const confirmationElement = document.getElementById('confirmation');
  confirmationElement.innerHTML = `
    <p><strong>Manager Name:</strong> ${name}</p>
    <p><strong>Email:</strong> ${email}</p>
    <p><strong>Phone Number:</strong> ${phoneno}</p>
    <p><strong>Team Name:</strong> ${team}</p>
    <p><strong>Captain:</strong> ${captain}</p>
    <p><strong>Tournament:</strong> ${tournament}</p>
    <p><strong>Match Format:</strong> ${match}</p>
  `;
}

showStep(currentStep);
