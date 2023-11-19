from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.contrib.auth import login, logout, authenticate
from django.db import IntegrityError
from .forms import TaskForm
from .models import Task
from django.utils import timezone

import string

# Create your views here.


def home(request):
    return render(request, 'home.html')


def signup(request):
    def deny_signup(msg):
        return render(request, 'signup.html', {
            'form': UserCreationForm,
            'error': f'ERROR: {msg}'
        })

    ALLOWED_CHARACTERS = string.ascii_letters + string.digits + '@.+-_'
    if request.method == 'GET':
        return render(request, 'signup.html', {
            'form': UserCreationForm
        })
    else:
        if len(request.POST['username']) > 150:
            return deny_signup('Username is too long. Max is 150 characters')
        elif len(request.POST['username']) < 4:
            return deny_signup('Username is too short. Min is 4 characters')
        if not request.POST['username'][0].islower():
            return deny_signup('Username must start with a lowercase letter')
        for c in request.POST['username']:
            if not c in ALLOWED_CHARACTERS:
                return deny_signup(f'Username contains a not allowed character ({c}). Only Letters, digits and @.+-_ is allowed')
        if request.POST['password1'] != request.POST['password2']:
            return deny_signup('Passwords do not match')
        elif len(request.POST['password1']) < 8:
            return deny_signup('Password lenght must be at least 8 characters')
        elif request.POST['password1'] == request.POST['password2']:
            # Register user
            print(f'Username: {request.POST['username']}')
            try:
                print(f'Password: {request.POST['username']}')
                user = User.objects.create_user(
                    username=request.POST['username'], password=request.POST['password1'])
                user.save()
                login(request, user)
                return redirect('tasks')
            except IntegrityError:
                return deny_signup('Username already exists. Please try with another')

def signin(request):
    if request.method == 'GET':
        return render(request, 'signin.html', {
            'form': AuthenticationForm
        })
    else:
        user = authenticate(
            request, username=request.POST['username'], password=request.POST['password'])
        if user is None:
            return render(request, 'signin.html', {
                'form': AuthenticationForm,
                'error': 'DENIED: Username or Password is incorrect'
            })
        else:
            login(request, user)
            return redirect('tasks')


@login_required
def tasks(request):
    tasks = Task.objects.filter(user=request.user).order_by('-created')
    return render(request, 'tasks.html', {
        'tasks': tasks
    })


@login_required
def create_task(request):
    if request.method == 'GET':
        return render(request, 'create_task.html', {
            'form': TaskForm
        })
    else:
        try:
            form = TaskForm(request.POST)
            new_task = form.save(commit=False)
            new_task.user = request.user
            new_task.save()
            return redirect('tasks')
        except Exception as e:
            return render(request, 'create_task.html', {
                'form': TaskForm,
                'error': str(e)
            })


@login_required
def task_detail(request, task_id):
    task = get_object_or_404(Task, pk=task_id, user=request.user)
    try:
        if request.method == 'GET':
            form = TaskForm(instance=task)
            return render(request, 'task_detail.html', {
                'task': task,
                'form': form
            })
        else:
            form = TaskForm(request.POST, instance=task)
            form.save()
            return redirect('tasks')
    except Exception as e:
        e = str(e)
        form = TaskForm(instance=task)
        return render(request, 'task_detail.html', {
            'task': task,
            'form': form,
            'error' : e
        })


@login_required
def complete_task(request, task_id):
    task = get_object_or_404(Task, pk=task_id, user=request.user)
    if request.method == 'POST':
        task.datecompleted = timezone.now()
        task.save()
        return redirect('tasks')


@login_required
def delete_task(request, task_id):
    task = get_object_or_404(Task, pk=task_id, user=request.user)
    if request.method == 'POST':
        task.delete()
        return redirect('tasks')


@login_required
def signout(request):
    logout(request)
    return redirect('home')
