import axios from 'axios';
import { Task, CreateTaskRequest, UpdateTaskRequest } from '@/types/task';

const API_BASE_URL = 'https://localhost:7079/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const taskApi = {
  // Get all tasks with optional filtering and pagination
  getTasks: (priority?: string, status?: string, page?: number, pageSize?: number) => {
    const params = new URLSearchParams();
    if (priority) params.append('priority', priority);
    if (status) params.append('status', status);
    if (page) params.append('page', page.toString());
    if (pageSize) params.append('pageSize', pageSize.toString());
    
    return api.get<Task[]>(`/tasks${params.toString() ? `?${params.toString()}` : ''}`);
  },

  // Get task by ID
  getTask: (id: number) => api.get<Task>(`/tasks/${id}`),

  // Create new task
  createTask: (task: CreateTaskRequest) => api.post<Task>('/tasks', task),

  // Update existing task
  updateTask: (task: UpdateTaskRequest) => api.put<Task>(`/tasks/${task.id}`, task),

  // Delete task
  deleteTask: (id: number) => api.delete(`/tasks/${id}`),
};
