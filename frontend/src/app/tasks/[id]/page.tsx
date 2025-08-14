'use client';

import { useState, useEffect } from 'react';
import { useRouter, useParams } from 'next/navigation';
import { taskApi } from '@/services/taskApi';
import { Task } from '@/types/task';
import { ArrowLeft, Edit, Trash2, Calendar, Clock, Flag, CheckCircle } from 'lucide-react';
import Link from 'next/link';

const TaskDetailPage = () => {
  const router = useRouter();
  const params = useParams();
  const taskId = parseInt(params.id as string);
  
  const [task, setTask] = useState<Task | null>(null);
  const [loading, setLoading] = useState(true);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    const loadTask = async () => {
      try {
        const response = await taskApi.getTask(taskId);
        setTask(response.data);
      } catch (error) {
        console.error('Error loading task:', error);
        router.push('/');
      } finally {
        setLoading(false);
      }
    };

    if (taskId) {
      loadTask();
    }
  }, [taskId, router]);

  const handleDelete = async () => {
    if (window.confirm('Are you sure you want to delete this task? This action cannot be undone.')) {
      setDeleting(true);
      try {
        await taskApi.deleteTask(taskId);
        router.push('/');
      } catch (error) {
        console.error('Error deleting task:', error);
        alert('Error deleting task. Please try again.');
      } finally {
        setDeleting(false);
      }
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'High': return 'text-red-600 bg-red-50 border-red-200';
      case 'Medium': return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'Low': return 'text-green-600 bg-green-50 border-green-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Completed': return 'text-green-600 bg-green-50 border-green-200';
      case 'InProgress': return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'Pending': return 'text-gray-600 bg-gray-50 border-gray-200';
      default: return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getPriorityIcon = (priority: string) => {
    switch (priority) {
      case 'High': return <Flag className="text-red-600" size={20} />;
      case 'Medium': return <Flag className="text-yellow-600" size={20} />;
      case 'Low': return <Flag className="text-green-600" size={20} />;
      default: return <Flag className="text-gray-600" size={20} />;
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Completed': return <CheckCircle className="text-green-600" size={20} />;
      case 'InProgress': return <Clock className="text-blue-600" size={20} />;
      case 'Pending': return <Clock className="text-gray-600" size={20} />;
      default: return <Clock className="text-gray-600" size={20} />;
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-100 py-8">
        <div className="container mx-auto px-4 max-w-4xl">
          <div className="text-center py-12">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            <p className="mt-2 text-gray-600">Loading task...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!task) {
    return (
      <div className="min-h-screen bg-gray-100 py-8">
        <div className="container mx-auto px-4 max-w-4xl">
          <div className="text-center py-12">
            <p className="text-gray-500 text-lg">Task not found</p>
            <Link
              href="/"
              className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
            >
              <ArrowLeft size={20} />
              Back to Tasks
            </Link>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100 py-8">
      <div className="container mx-auto px-4 max-w-4xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-4">
            <Link
              href="/"
              className="flex items-center gap-2 text-blue-600 hover:text-blue-800"
            >
              <ArrowLeft size={20} />
              Back to Tasks
            </Link>
            <h1 className="text-3xl font-bold text-gray-900">Task Details</h1>
          </div>
          
          <div className="flex gap-3">
            <Link
              href={`/tasks/${task.id}/edit`}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors"
            >
              <Edit size={20} />
              Edit
            </Link>
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
            >
              <Trash2 size={20} />
              {deleting ? 'Deleting...' : 'Delete'}
            </button>
          </div>
        </div>

        {/* Task Detail Card */}
        <div className="bg-white rounded-lg shadow-md overflow-hidden">
          {/* Task Header */}
          <div className="p-6 border-b border-gray-200">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <h2 className="text-2xl font-bold text-gray-900 mb-2">{task.title}</h2>
                <div className="flex items-center gap-4 mb-4">
                  <div className="flex items-center gap-2">
                    {getPriorityIcon(task.priority)}
                    <span className={`inline-flex px-3 py-1 text-sm font-semibold rounded-full border ${getPriorityColor(task.priority)}`}>
                      {task.priority} Priority
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {getStatusIcon(task.status)}
                    <span className={`inline-flex px-3 py-1 text-sm font-semibold rounded-full border ${getStatusColor(task.status)}`}>
                      {task.status}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Task Content */}
          <div className="p-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Main Content */}
              <div className="lg:col-span-2">
                <div className="mb-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
                  <div className="bg-gray-50 rounded-lg p-4">
                    <p className="text-gray-700 whitespace-pre-wrap">{task.description}</p>
                  </div>
                </div>
              </div>

              {/* Sidebar */}
              <div className="lg:col-span-1">
                <div className="space-y-6">
                  {/* Due Date */}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2 flex items-center gap-2">
                      <Calendar size={16} />
                      Due Date
                    </h4>
                    <p className="text-gray-700">
                      {task.dueDate ? formatDate(task.dueDate) : 'No due date set'}
                    </p>
                  </div>

                  {/* Task Info */}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Task Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-600">Task ID:</span>
                        <span className="font-medium">#{task.id}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Priority:</span>
                        <span className={`font-medium ${
                          task.priority === 'High' ? 'text-red-600' :
                          task.priority === 'Medium' ? 'text-yellow-600' :
                          'text-green-600'
                        }`}>
                          {task.priority}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-600">Status:</span>
                        <span className={`font-medium ${
                          task.status === 'Completed' ? 'text-green-600' :
                          task.status === 'InProgress' ? 'text-blue-600' :
                          'text-gray-600'
                        }`}>
                          {task.status}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Timestamps */}
                  <div>
                    <h4 className="text-sm font-medium text-gray-900 mb-2">Timestamps</h4>
                    <div className="space-y-2 text-sm text-gray-600">
                      <div>
                        <span className="block text-xs text-gray-500">Created</span>
                        <span>{formatDate(task.createdAt)}</span>
                      </div>
                      <div>
                        <span className="block text-xs text-gray-500">Last Updated</span>
                        <span>{formatDate(task.updatedAt)}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default TaskDetailPage;
